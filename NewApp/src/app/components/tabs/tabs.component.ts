import { Component, OnInit } from '@angular/core';
import { Router } from '@angular/router';
import { IonicModule } from '@ionic/angular';



@Component({
  selector: 'app-tabs',
  imports: [IonicModule],  // Ajoute cette ligne
  templateUrl: './tabs.component.html',
  styleUrls: ['./tabs.component.css']
})


export class TabsComponent {
  constructor(private router: Router) {}

  navigateTo(route: string) {
    this.router.navigate([route]);
  }
}
