import { ComponentFixture, TestBed } from '@angular/core/testing';
import { MedecinDetailPage } from './medecin-detail.page';

describe('MedecinDetailPage', () => {
  let component: MedecinDetailPage;
  let fixture: ComponentFixture<MedecinDetailPage>;

  beforeEach(() => {
    fixture = TestBed.createComponent(MedecinDetailPage);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
