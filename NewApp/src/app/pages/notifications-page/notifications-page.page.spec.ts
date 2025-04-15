import { ComponentFixture, TestBed } from '@angular/core/testing';
import { NotificationsPage } from './notifications-page.page';

describe('NotificationsPagePage', () => {
  let component: NotificationsPage;
  let fixture: ComponentFixture<NotificationsPage>;

  beforeEach(() => {
    fixture = TestBed.createComponent(NotificationsPage);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
